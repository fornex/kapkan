// Package app wires the kapkan components — ingest, engine, mitigation,
// notification and the API — into a single startable/stoppable unit. Both the
// command binary and the end-to-end test construct an App, so the wiring is
// exercised exactly as it runs in production.
package app

import (
	"context"
	"fmt"
	"log/slog"
	"sync"

	"github.com/kapkan-io/kapkan/internal/api"
	"github.com/kapkan-io/kapkan/internal/config"
	"github.com/kapkan-io/kapkan/internal/engine"
	"github.com/kapkan-io/kapkan/internal/ingest"
	"github.com/kapkan-io/kapkan/internal/mitigate"
	"github.com/kapkan-io/kapkan/internal/notify"
)

// App holds the wired components and their lifecycle handles.
type App struct {
	Store    *config.Store
	Engine   *engine.Engine
	Ingest   *ingest.Ingester
	Mitigate *mitigate.Mitigator
	Notify   *notify.Notifier
	API      *api.Server

	log    *slog.Logger
	cancel context.CancelFunc
	wg     sync.WaitGroup
	apiErr chan error
}

// New builds all components from the configuration store. It does not bind
// sockets or start goroutines; call Start for that.
func New(store *config.Store, log *slog.Logger) (*App, error) {
	a := &App{Store: store, log: log, apiErr: make(chan error, 1)}

	a.Engine = engine.New(store, engine.WithLogger(log))

	mit, err := mitigate.New(store, log)
	if err != nil {
		return nil, fmt.Errorf("init mitigation: %w", err)
	}
	a.Mitigate = mit

	a.Notify = notify.New(store, log)

	ing, err := ingest.New(store, a.Engine.Process, log)
	if err != nil {
		return nil, fmt.Errorf("init ingest: %w", err)
	}
	a.Ingest = ing

	a.API = api.New(store, a.Engine, mit, log)
	return a, nil
}

// Start brings up the BGP speaker, binds the UDP listeners and the API, and
// launches the engine evaluation loop and the event consumer. It returns once
// everything is started; use APIError to observe a fatal API failure.
func (a *App) Start(ctx context.Context) error {
	runCtx, cancel := context.WithCancel(ctx)
	a.cancel = cancel

	if err := a.Mitigate.Start(runCtx); err != nil {
		cancel()
		return fmt.Errorf("start mitigation: %w", err)
	}
	if err := a.Ingest.Start(); err != nil {
		cancel()
		return fmt.Errorf("start ingest: %w", err)
	}

	go func() { a.apiErr <- a.API.ListenAndServe(runCtx) }()

	a.wg.Add(2)
	go func() { defer a.wg.Done(); a.Engine.Run(runCtx) }()
	go func() { defer a.wg.Done(); a.consumeEvents(runCtx) }()
	return nil
}

// APIError returns a channel that yields the API server's terminal error (or
// nil on clean shutdown).
func (a *App) APIError() <-chan error { return a.apiErr }

// Stop tears down ingest, the engine loop and the BGP speaker in the safe
// order: stop accepting flows first, then drain.
func (a *App) Stop() {
	a.Ingest.Stop()
	if a.cancel != nil {
		a.cancel()
	}
	a.wg.Wait()
	a.Mitigate.Stop()
}

// consumeEvents bridges engine attack events to mitigation, the API attack
// log and notifications.
func (a *App) consumeEvents(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case ev := <-a.Engine.Events():
			switch ev.Kind {
			case engine.AttackStarted:
				ban := a.Mitigate.OnAttackStarted(ev)
				a.API.RecordAttackStarted(ev, ban)
				a.Notify.NotifyAttackStarted(ctx, ev, ban)
			case engine.AttackEnded:
				ban := a.Mitigate.OnAttackEnded(ev)
				a.API.RecordAttackEnded(ev, ban)
				a.Notify.NotifyAttackEnded(ctx, ev, ban)
			}
		}
	}
}
