package main

// `kapkan scrub` — the scrub-node role.
//
// Same binary, different job: no detection, no BGP, no listeners. The box
// receives traffic the brain diverted at it, and this command keeps the local
// XDP data plane enforcing the brain's rule table (internal/scrub owns the
// loop). Everything role-specific lives in its own scrub.yaml; the daemon's
// kapkan.yaml and flags are not read.

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"log/slog"

	"github.com/kapkan-io/kapkan/internal/config"
	"github.com/kapkan-io/kapkan/internal/dataplane"
	"github.com/kapkan-io/kapkan/internal/logging"
	"github.com/kapkan-io/kapkan/internal/scrub"
)

// runScrubCommand parses `kapkan scrub` flags and runs the agent until a
// signal. The global flags are deliberately not inherited: -config there
// defaults to the DAEMON's file, and a scrub node accidentally reading
// kapkan.yaml should be a loud usage error, not a subtle one.
func runScrubCommand(args []string, f *cliFlags, _, errOut io.Writer) int {
	// Global flags this role deliberately does not read: silently ignoring
	// `kapkan -config x.yaml scrub` would run against a DIFFERENT file than
	// the operator named, which is worse than a usage error.
	for _, name := range []string{"config", "log-format", "log-level"} {
		if f.wasSet(name) {
			lineWriter{errOut}.printf(
				"kapkan scrub: the global -%s flag is not read by this role; pass it AFTER the command: kapkan scrub -%s ...\n",
				name, name)
			return exitUsage
		}
	}

	fs := subcommandFlags("scrub", errOut)
	cfgPath := fs.String("config", "/etc/kapkan/scrub.yaml", "path to the scrub-node configuration")
	logFormat := fs.String("log-format", "json", "log format: json|text")
	logLevel := fs.String("log-level", "info", "log level: debug|info|warn|error")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return exitOK // help is a request, not a mistake
		}
		return exitUsage
	}
	if fs.NArg() > 0 {
		lineWriter{errOut}.printf("kapkan scrub: unexpected argument %q\n", fs.Arg(0))
		return exitUsage
	}

	sc, err := config.LoadScrub(*cfgPath)
	if err != nil {
		lineWriter{errOut}.printf("kapkan scrub: %v\n", err)
		return 1
	}
	token := os.Getenv(sc.Controller.TokenEnv)
	if token == "" {
		lineWriter{errOut}.printf("kapkan scrub: the agent token is empty — set %s\n", sc.Controller.TokenEnv)
		return 1
	}

	log := logging.New(*logFormat, *logLevel)
	if err := runScrubAgent(sc, token, log); err != nil {
		log.Error("fatal", "err", err)
		return 1
	}
	return exitOK
}

func runScrubAgent(sc *config.ScrubConfig, token string, log *slog.Logger) error {
	opts, err := dataplane.OptionsFromScrub(sc)
	if err != nil {
		return err
	}
	opts.Log = log

	log.Info("starting kapkan scrub",
		"controller", sc.Controller.URL, "node", sc.Controller.Name,
		"dry_run", sc.DryRunResolved(), "interfaces", opts.Interfaces)
	if sc.DryRunResolved() {
		log.Warn("DRY-RUN mode (the remote-role default): rules are installed and counted, nothing is dropped")
	} else {
		log.Warn("LIVE mode: this node WILL drop diverted traffic in the kernel")
	}
	if strings.HasPrefix(sc.Controller.URL, "http://") {
		log.Warn("controller.url is plaintext http: the agent token crosses the network unencrypted — use https outside a lab")
	}

	mgr, err := dataplane.Open(opts)
	if err != nil {
		return fmt.Errorf("open data plane: %w", err)
	}

	agent, err := scrub.New(scrub.Options{
		BaseURL:        strings.TrimRight(sc.Controller.URL, "/"),
		Token:          token,
		Node:           sc.Controller.Name,
		DryRun:         sc.DryRunResolved(),
		Backend:        dataplane.NewInstaller(mgr, log),
		Status:         managerStatus(mgr),
		Log:            log,
		ReportInterval: time.Duration(sc.Controller.ReportIntervalSeconds) * time.Second,
	})
	if err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	log.Info("kapkan scrub running")
	agent.Run(ctx)

	// on_exit governs what a stopped node leaves behind, exactly as it does
	// for the daemon: keep (default) leaves the pinned program enforcing —
	// dynamic rules age out on their own deadlines — detach fails open.
	if err := mgr.Close(sc.DataplaneCfg.OnExit); err != nil {
		log.Error("closing the data plane failed", "err", err)
	}
	log.Info("kapkan scrub stopped")
	return nil
}

// managerStatus adapts the Manager into the agent's advisory Status: the
// effective XDP mode across interfaces and the datapath's real drop totals
// (terminal drop_* verdicts only — observation counters co-occur with a
// terminal one and would double-count).
func managerStatus(mgr *dataplane.Manager) scrub.Status {
	return func() (string, uint64, uint64) {
		h := mgr.Health()
		mode := ""
		for _, i := range h.Interfaces {
			if !i.Attached || i.Mode == "" {
				continue
			}
			switch {
			case mode == "":
				mode = i.Mode
			case mode != i.Mode:
				mode = "mixed"
			}
		}
		var pkts, bytes_ uint64
		if snap, err := mgr.Stats(); err == nil {
			for name, c := range snap.Verdicts {
				if strings.HasPrefix(name, "drop_") {
					pkts += c.Pkts
					bytes_ += c.Bytes
				}
			}
		}
		return mode, pkts, bytes_
	}
}
