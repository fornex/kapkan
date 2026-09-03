package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/kapkan-io/kapkan/internal/config"
	"github.com/kapkan-io/kapkan/internal/edge/acme"
	"github.com/kapkan-io/kapkan/internal/edge/node"
	"github.com/kapkan-io/kapkan/internal/edge/unixsock"
	"github.com/kapkan-io/kapkan/internal/logging"
)

// runEdgeCommand parses `kapkan edge` flags and runs the edge role until a
// signal. As with scrub, the global flags are deliberately not inherited: a
// node accidentally reading kapkan.yaml must be a loud usage error.
func runEdgeCommand(args []string, f *cliFlags, _, errOut io.Writer) int {
	for _, name := range []string{"config", "log-format", "log-level"} {
		if f.wasSet(name) {
			lineWriter{errOut}.printf(
				"kapkan edge: the global -%s flag is not read by this role; pass it AFTER the command: kapkan edge -%s ...\n",
				name, name)
			return exitUsage
		}
	}

	fs := subcommandFlags("edge", errOut)
	cfgPath := fs.String("config", "/etc/kapkan/edge.yaml", "path to the edge-node configuration")
	logFormat := fs.String("log-format", "json", "log format: json|text")
	logLevel := fs.String("log-level", "info", "log level: debug|info|warn|error")
	checkOnly := fs.Bool("check", false, "validate the configuration and what it names on this box, then exit")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return exitOK
		}
		return exitUsage
	}
	if fs.NArg() > 0 {
		lineWriter{errOut}.printf("kapkan edge: unexpected argument %q\n", fs.Arg(0))
		return exitUsage
	}

	ec, err := config.LoadEdgeNode(*cfgPath)
	if err != nil {
		lineWriter{errOut}.printf("kapkan edge: %v\n", err)
		return 1
	}
	if *checkOnly {
		problems, warnings := edgePreflight(ec)
		for _, w := range warnings {
			lineWriter{errOut}.printf("kapkan edge: warning: %s\n", w)
		}
		for _, p := range problems {
			lineWriter{errOut}.printf("kapkan edge: %s\n", p)
		}
		if len(problems) > 0 {
			return 1
		}
		lineWriter{errOut}.printf("kapkan edge: %s is valid (node %s, brain %s, dry_run %v, state_dir %s, sockets_dir %s, terminator %s)\n",
			*cfgPath, ec.Controller.Name, ec.Controller.URL, ec.DryRunResolved(), ec.StateDir, ec.SocketsDir, ec.Terminator.Binary)
		return exitOK
	}
	token := os.Getenv(ec.Controller.TokenEnv)
	if token == "" {
		lineWriter{errOut}.printf("kapkan edge: the agent token is empty — set %s\n", ec.Controller.TokenEnv)
		return 1
	}

	log := logging.New(*logFormat, *logLevel)
	if err := runEdge(ec, token, log); err != nil {
		log.Error("kapkan edge failed", "err", err)
		return 1
	}
	return exitOK
}

// edgePreflight checks what -check can verify beyond the YAML's shape on the
// box it runs on. Problems fail the check; warnings do not — -check may run
// outside the unit's environment (no EnvironmentFile) or before the
// terminator is installed, so an absent secret or binary is reported, not
// refused.
func edgePreflight(ec *config.EdgeNodeConfig) (problems, warnings []string) {
	if os.Getenv(ec.Controller.TokenEnv) == "" {
		warnings = append(warnings, fmt.Sprintf("the agent token variable %s is not set in this environment (the unit reads /etc/kapkan/edge.env)", ec.Controller.TokenEnv))
	}
	if _, err := ec.ACME.ResolveEAB(); err != nil {
		if strings.Contains(err.Error(), "empty or unset") {
			warnings = append(warnings, err.Error()+" in this environment")
		} else {
			problems = append(problems, err.Error())
		}
	}
	if ec.SocketGroup != "" {
		if _, err := unixsock.GroupID(ec.SocketGroup); err != nil {
			problems = append(problems, fmt.Sprintf("socket_group: %v", err))
		}
	}
	if _, err := exec.LookPath(ec.Terminator.Binary); err != nil {
		warnings = append(warnings, fmt.Sprintf("terminator.binary %q is not on PATH here (nginx -t and reloads will fail until it is)", ec.Terminator.Binary))
	}
	if ec.Terminator.MainConf != "" {
		if _, err := os.Stat(ec.Terminator.MainConf); err != nil {
			warnings = append(warnings, fmt.Sprintf("terminator.main_conf: %v", err))
		}
	}
	if ec.Terminator.Reload == config.EdgeReloadCommand {
		if _, err := exec.LookPath(ec.Terminator.Command[0]); err != nil {
			warnings = append(warnings, fmt.Sprintf("terminator.command %q is not on PATH here", ec.Terminator.Command[0]))
		}
	}
	return problems, warnings
}

// edgeNodeOptions maps the validated edge.yaml onto the node's options.
func edgeNodeOptions(ec *config.EdgeNodeConfig, token string, eab map[string]config.EdgeEABCredentials, log *slog.Logger) node.Options {
	var bindings map[string]acme.EAB
	if len(eab) > 0 {
		bindings = make(map[string]acme.EAB, len(eab))
		for dir, c := range eab {
			bindings[dir] = acme.EAB{KID: c.KID, HMACKey: c.HMACKey}
		}
	}
	return node.Options{
		Brain:          strings.TrimRight(ec.Controller.URL, "/"),
		Token:          token,
		Name:           ec.Controller.Name,
		DryRun:         ec.DryRunResolved(),
		StateDir:       ec.StateDir,
		SocketsDir:     ec.SocketsDir,
		SocketGroup:    ec.SocketGroup,
		Terminator:     node.Terminator{Binary: ec.Terminator.Binary, MainConf: ec.Terminator.MainConf, Reload: ec.Terminator.Reload, PIDFile: ec.Terminator.PIDFile, Command: ec.Terminator.Command},
		ACME:           node.ACME{Directory: ec.ACME.Directory, Fallback: ec.ACME.Fallback, Contact: ec.ACME.Contact, EAB: bindings, Disabled: ec.ACME.Disabled},
		ReportInterval: time.Duration(ec.Controller.ReportIntervalSeconds) * time.Second,
		StatusListen:   ec.StatusListen,
		OmitCatchAll:   ec.OmitCatchAll,
		DisableIPv6:    ec.DisableIPv6,
		Logger:         log,
	}
}

// runEdge builds and runs the node; split out so the CLI layer stays thin.
func runEdge(ec *config.EdgeNodeConfig, token string, log *slog.Logger) error {
	// EAB HMAC keys are secrets and live in the environment, like the token.
	eab, err := ec.ACME.ResolveEAB()
	if err != nil {
		return err
	}
	n, err := node.New(edgeNodeOptions(ec, token, eab, log))
	if err != nil {
		return err
	}
	log.Info("starting kapkan edge", "controller", ec.Controller.URL, "node", ec.Controller.Name, "dry_run", ec.DryRunResolved())
	if ec.DryRunResolved() {
		log.Warn("DRY-RUN mode (the remote-role default): decisions are counted and marked, nothing is refused")
	} else {
		log.Warn("LIVE mode: this node WILL refuse requests the decision service denies")
	}
	if strings.HasPrefix(ec.Controller.URL, "http://") {
		log.Warn("controller.url is plaintext http: the agent token crosses the network unencrypted — use https outside a lab")
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	err = n.Run(ctx)
	log.Info("kapkan edge stopped")
	if err != nil {
		return fmt.Errorf("edge: %w", err)
	}
	return nil
}
